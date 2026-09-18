"""
Определение окружения (Docker/Kubernetes) на сервере.

Используется двумя местами:
- install.sh при каждом запуске - чтобы предложить поставить правила
  логирования не только на INPUT (хост), но и на DOCKER-USER / KUBE-*
  цепочки (см. install-logging-rules.sh).
- ботом (команда /env) - чтобы показать администратору то же самое,
  не заходя на сервер по SSH.

Всё здесь - best-effort: если docker/kubectl/iptables недоступны или нет
прав их вызвать, функции просто возвращают "не обнаружено"/пустой список,
без исключений наружу.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass, field

# Цепочки iptables/nftables, которые нас интересуют:
# - DOCKER-USER              - весь трафик на опубликованные Docker-порты
# - KUBE-EXTERNAL-SERVICES   - NodePort/LoadBalancer в iptables-режиме kube-proxy (совр. k8s)
# - KUBE-NODEPORTS           - то же самое в более старых версиях k8s
# - KUBE-SERVICES            - точка входа диспетчеризации сервисов k8s (менее полезна для LOG,
#                               но проверяем на случай нестандартных сборок)
INTERESTING_CHAINS = [
    "DOCKER-USER",
    "KUBE-EXTERNAL-SERVICES",
    "KUBE-NODEPORTS",
    "KUBE-SERVICES",
]


def _run(cmd: list[str], timeout: float = 5.0) -> str | None:
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
        if result.returncode != 0:
            return None
        return result.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None


def detect_docker() -> bool:
    if os.path.exists("/var/run/docker.sock"):
        return True
    if shutil.which("docker") and _run(["docker", "info", "--format", "{{.ServerVersion}}"]):
        return True
    return False


def detect_kubernetes() -> bool:
    # Поды внутри самого кластера (если бот вдруг запущен в k8s)
    if os.path.exists("/var/run/secrets/kubernetes.io/serviceaccount") or os.environ.get(
        "KUBERNETES_SERVICE_HOST"
    ):
        return True
    # Узел с настроенным kubectl (control-plane или воркер с доступом к API)
    if shutil.which("kubectl") and _run(["kubectl", "version", "--client", "-o", "json"]):
        kubeconfig = os.environ.get("KUBECONFIG") or os.path.expanduser("~/.kube/config")
        if os.path.exists(kubeconfig):
            return True
    # kubelet/kube-proxy запущены на этой машине как systemd-юниты - тоже признак узла k8s
    if shutil.which("systemctl") and _run(["systemctl", "is-active", "kubelet"]) == "active\n":
        return True
    return False


def detect_kube_proxy_mode() -> str | None:
    """'iptables', 'ipvs' или None если определить не удалось. Важно для
    install.sh: в ipvs-режиме kube-proxy не создаёт цепочки KUBE-* в
    iptables, и логирование NodePort-трафика через iptables LOG не сработает."""
    out = _run(["ipvsadm", "-L", "-n"])
    if out and out.strip():
        return "ipvs"
    if list_iptables_chains():
        for chain in INTERESTING_CHAINS:
            if chain.startswith("KUBE-"):
                if _chain_exists(chain):
                    return "iptables"
    return None


def list_iptables_chains() -> list[str]:
    """Список имён цепочек iptables, доступных на хосте (пустой список,
    если iptables недоступен/нет прав - без исключения)."""
    out = _run(["iptables", "-S"])
    if not out:
        return []
    chains = []
    for line in out.splitlines():
        if line.startswith("-N ") or line.startswith("-P "):
            chains.append(line.split()[1])
    return chains


def _chain_exists(chain: str) -> bool:
    return _run(["iptables", "-L", chain, "-n"]) is not None


def list_docker_published_ports() -> list[dict]:
    """docker ps: имя контейнера + опубликованные порты. Пустой список,
    если docker недоступен или контейнеров нет."""
    out = _run(["docker", "ps", "--format", "{{.Names}}\t{{.Ports}}"])
    if not out:
        return []
    result = []
    for line in out.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t", 1)
        name = parts[0]
        ports = parts[1] if len(parts) > 1 else ""
        if ports.strip():
            result.append({"name": name, "ports": ports.strip()})
    return result


def list_k8s_nodeport_services() -> list[dict]:
    """kubectl get svc -A: только сервисы типа NodePort/LoadBalancer (то,
    что реально принимает внешний трафик мимо обычного INPUT/DOCKER-USER)."""
    out = _run(["kubectl", "get", "svc", "-A", "-o", "json"], timeout=10.0)
    if not out:
        return []
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return []
    result = []
    for item in data.get("items", []):
        spec = item.get("spec", {})
        svc_type = spec.get("type", "")
        if svc_type not in ("NodePort", "LoadBalancer"):
            continue
        meta = item.get("metadata", {})
        ports = [
            f"{p.get('port')}->{p.get('nodePort', '?')}/{p.get('protocol', 'TCP')}"
            for p in spec.get("ports", [])
        ]
        result.append(
            {
                "namespace": meta.get("namespace"),
                "name": meta.get("name"),
                "type": svc_type,
                "ports": ports,
            }
        )
    return result


@dataclass
class EnvironmentSummary:
    docker: bool = False
    kubernetes: bool = False
    kube_proxy_mode: str | None = None
    docker_containers: list[dict] = field(default_factory=list)
    k8s_services: list[dict] = field(default_factory=list)
    chains_present: list[str] = field(default_factory=list)
    chains_armed: list[str] = field(default_factory=list)

    def any_container_platform(self) -> bool:
        return self.docker or self.kubernetes

    def needs_extra_logging_rules(self) -> bool:
        """Есть контейнерная платформа, у которой есть релевантная цепочка,
        но CONN-логирование в неё ещё не поставлено."""
        relevant = {c for c in self.chains_present if c in INTERESTING_CHAINS}
        return bool(relevant - set(self.chains_armed))


def _chain_has_conn_log_rule(chain: str, log_prefix: str = "CONN: ") -> bool:
    out = _run(["iptables", "-S", chain])
    if not out:
        return False
    return f'--log-prefix "{log_prefix}"' in out or f"--log-prefix {log_prefix}" in out


def summarize_environment(log_prefix: str = "CONN: ") -> EnvironmentSummary:
    summary = EnvironmentSummary()
    summary.docker = detect_docker()
    summary.kubernetes = detect_kubernetes()

    if summary.docker or summary.kubernetes:
        summary.kube_proxy_mode = detect_kube_proxy_mode()
        present_chains = set(list_iptables_chains())
        summary.chains_present = [c for c in INTERESTING_CHAINS if c in present_chains]
        summary.chains_armed = [
            c for c in summary.chains_present if _chain_has_conn_log_rule(c, log_prefix)
        ]

    if summary.docker:
        summary.docker_containers = list_docker_published_ports()
    if summary.kubernetes:
        summary.k8s_services = list_k8s_nodeport_services()

    return summary


def format_summary_text(summary: EnvironmentSummary) -> str:
    """Человекочитаемое резюме для команды /env и для install.sh."""
    lines = []
    if not summary.any_container_platform():
        lines.append("Docker/Kubernetes на этом сервере не обнаружены.")
        return "\n".join(lines)

    if summary.docker:
        lines.append(f"🐳 Docker обнаружен, контейнеров с опубликованными портами: "
                      f"{len(summary.docker_containers)}")
    if summary.kubernetes:
        mode = summary.kube_proxy_mode or "неизвестен"
        lines.append(f"☸️ Kubernetes обнаружен, режим kube-proxy: {mode}, "
                      f"NodePort/LoadBalancer сервисов: {len(summary.k8s_services)}")

    if summary.chains_present:
        lines.append(f"Найдены цепочки: {', '.join(summary.chains_present)}")
    if summary.chains_armed:
        lines.append(f"Логирование CONN уже стоит в: {', '.join(summary.chains_armed)}")

    if summary.needs_extra_logging_rules():
        lines.append(
            "⚠️ Есть цепочки без логирования сканов - рекомендуется прогнать "
            "install-logging-rules.sh (или пункт меню install.sh) ещё раз."
        )
    elif summary.kube_proxy_mode == "ipvs":
        lines.append(
            "ℹ️ kube-proxy работает в режиме ipvs: NodePort-трафик не проходит через "
            "iptables-цепочки KUBE-*, поэтому автоматическое логирование для него "
            "недоступно - опирайтесь на мониторинг хоста (INPUT)."
        )

    return "\n".join(lines)
