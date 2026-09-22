"""Generate evidence-bound structured trajectories in a restricted Docker canary lab."""
from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
from typing import Any

from .models import canonical_json, now
from .storage import Store
from .trajectories import SCHEMA, export_trajectories, import_trajectories, validate_trajectory


SCENARIO_TYPES = (
    ("technical_vulnerability", "xss"),
    ("technical_vulnerability", "sql_injection"),
    ("technical_vulnerability", "command_injection"),
    ("technical_vulnerability", "ssrf"),
    ("technical_vulnerability", "csrf"),
    ("business_logic", "parameter_tampering"),
    ("business_logic", "mass_assignment"),
    ("business_logic", "authorization_replay"),
    ("business_logic", "duplicate_submission"),
    ("business_logic", "workflow_order_bypass"),
)
VARIANTS = ("baseline", "alternate_field", "encoded_input", "new_session", "state_refresh", "replay")
OBSTACLES = ("none", "session_expired", "field_alias", "input_filter", "state_version")
METHOD_PROFILES: dict[str, dict[str, str]] = {
    "xss": {
        "name_zh": "XSS",
        "test_point_zh": "HTML 输出与编码边界",
        "hypothesis_zh": "若不可信标记在输出点未被编码，合成 DOM 对照中会保留标记结构。",
        "safe_action_zh": "在内存 HTML 模型中对比未编码与编码分支，不访问浏览器或外部页面。",
        "success_criteria_zh": "仅未编码分支保留唯一 canary 标记，编码对照分支不保留。",
    },
    "sql_injection": {
        "name_zh": "SQL 注入",
        "test_point_zh": "SQL 字符串拼接与参数化查询边界",
        "hypothesis_zh": "若查询拼接不可信输入，内存数据库的返回行会与参数化对照不同。",
        "safe_action_zh": "仅在容器内存 SQLite 中对比拼接与参数化路径。",
        "success_criteria_zh": "拼接路径出现额外合成行，参数化对照返回零行。",
    },
    "command_injection": {
        "name_zh": "命令注入",
        "test_point_zh": "固定容器 shell 文本与参数边界",
        "hypothesis_zh": "若合成命令文本进入 shell 边界，唯一 canary 会出现在隔离输出中。",
        "safe_action_zh": "执行代码内置的固定 printf canary，不接受用户命令或外部脚本。",
        "success_criteria_zh": "固定进程成功退出且隔离输出中出现唯一 canary。",
    },
    "ssrf": {
        "name_zh": "SSRF",
        "test_point_zh": "URL 输入与内部资源路由边界",
        "hypothesis_zh": "若合成 URL 获取器信任输入，会命中进程内部的 canary 路由。",
        "safe_action_zh": "调用进程内字典路由，Docker 始终断网，不发出 HTTP 请求。",
        "success_criteria_zh": "仅进程内部路由返回与任务绑定的 metadata canary。",
    },
    "csrf": {
        "name_zh": "CSRF",
        "test_point_zh": "状态变更请求与 CSRF 令牌边界",
        "hypothesis_zh": "若合成状态处理器未校验令牌，无令牌请求仍会改变状态。",
        "safe_action_zh": "仅更新内存用户对象的合成邮箱字段。",
        "success_criteria_zh": "证据显示 token_supplied=false 且合成状态发生变更。",
    },
    "parameter_tampering": {
        "name_zh": "参数篡改",
        "test_point_zh": "客户端价格与服务端价格信任边界",
        "hypothesis_zh": "若合成结算信任客户端价格，最终计费会偏离服务端基准。",
        "safe_action_zh": "仅修改内存订单副本的合成价格字段。",
        "success_criteria_zh": "合成已收取价格与服务端基准不一致。",
    },
    "mass_assignment": {
        "name_zh": "绑定破坏（批量赋值）",
        "test_point_zh": "对象绑定字段与允许列表边界",
        "hypothesis_zh": "若合成绑定器未限制字段，特权字段会被批量写入。",
        "safe_action_zh": "仅对内存账户对象执行合成字段绑定。",
        "success_criteria_zh": "证据显示未列入允许列表的 role 字段被绑定。",
    },
    "authorization_replay": {
        "name_zh": "越权重放",
        "test_point_zh": "操作 nonce 与用户归属校验边界",
        "hypothesis_zh": "若合成授权处理器仅校验 nonce，其他用户可重放该操作。",
        "safe_action_zh": "在内存操作对象上对比 owner 与 actor，不发送网络请求。",
        "success_criteria_zh": "actor 与 owner 不同时，合成操作 nonce 仍被接受。",
    },
    "duplicate_submission": {
        "name_zh": "重复提交",
        "test_point_zh": "同一逻辑操作与幂等控制边界",
        "hypothesis_zh": "若合成处理器缺少幂等键，相同操作会被应用两次。",
        "safe_action_zh": "对内存计数器重复调用同一固定操作。",
        "success_criteria_zh": "同一合成操作被计数两次，而幂等期望为一次。",
    },
    "workflow_order_bypass": {
        "name_zh": "跳步乱序",
        "test_point_zh": "工作流状态转换与前置步骤边界",
        "hypothesis_zh": "若合成工作流未校验前置状态，未审批对象也可直接完成。",
        "safe_action_zh": "仅在内存状态机中尝试从初始态跳到完成态。",
        "success_criteria_zh": "completed=true 且 approved=false，证明合成前置状态未被强制。",
    },
}
OBSTACLE_PROFILES: dict[str, dict[str, str]] = {
    "none": {
        "name_zh": "无额外阻碍",
        "assessment_zh": "授权、字段、输入形式和状态版本均满足前置条件。",
        "strategy_zh": "保持原定范围，直接执行无害 canary 对照。",
    },
    "session_expired": {
        "name_zh": "会话过期",
        "assessment_zh": "初始会话不再有效，必须恢复授权实验会话后才能继续。",
        "strategy_zh": "刷新一次性实验会话，将原 canary 绑定到新会话后重试。",
    },
    "field_alias": {
        "name_zh": "字段别名",
        "assessment_zh": "输入字段名与实验 schema 的规范字段不一致。",
        "strategy_zh": "查询内置 schema 并解析别名，仅对映射后的合成字段重试。",
    },
    "input_filter": {
        "name_zh": "输入过滤",
        "assessment_zh": "初始表示形式不符合实验允许的 canary 格式。",
        "strategy_zh": "改用实验文档定义的规范 canary 表示，不尝试绕过真实防护。",
    },
    "state_version": {
        "name_zh": "状态版本过期",
        "assessment_zh": "任务引用的合成状态版本落后于当前版本。",
        "strategy_zh": "重新加载一次性状态，将 canary 重绑定到当前版本后重试。",
    },
}
CATEGORY_REQUIREMENTS = {
    "technical_vulnerability": "3",
    "business_logic": "4",
}
CHAIN_PHASES = (
    "define_scope",
    "form_hypothesis",
    "assess_obstacle",
    "recover_or_proceed",
    "execute_canary",
    "verify_evidence",
    "complete_task",
)


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_docker_scenarios(count: int = 3000, seed: str = "vulntools-docker-lab-v1") -> list[dict[str, Any]]:
    if type(count) is not int or count < len(SCENARIO_TYPES):
        raise ValueError(f"count must be an integer of at least {len(SCENARIO_TYPES)}")
    if not isinstance(seed, str) or not seed.strip():
        raise ValueError("seed must be nonempty")
    scenarios: list[dict[str, Any]] = []
    per_type = Counter()
    for ordinal in range(count):
        category, vulnerability_type = SCENARIO_TYPES[ordinal % len(SCENARIO_TYPES)]
        case_index = per_type[vulnerability_type]
        per_type[vulnerability_type] += 1
        canary = hashlib.sha256(f"{seed}:{vulnerability_type}:{case_index}".encode("utf-8")).hexdigest()[:24]
        scenario_id = f"docker-lab:{vulnerability_type}:{case_index:04d}:{canary[:8]}"
        obstacle = OBSTACLES[(case_index // len(VARIANTS)) % len(OBSTACLES)]
        expected_digest = hashlib.sha256(
            f"{scenario_id}|{vulnerability_type}|{canary}|passed".encode("utf-8")
        ).hexdigest()
        scenarios.append({
            "schema": "vulntools/docker-trajectory-scenario/v1",
            "scenario_id": scenario_id,
            "category": category,
            "vulnerability_type": vulnerability_type,
            "case_index": case_index,
            "variant": VARIANTS[case_index % len(VARIANTS)],
            "obstacle": obstacle,
            "canary": canary,
            "expected_digest": expected_digest,
            "authorized": True,
            "target_scope": "in-container synthetic canary only",
        })
    return scenarios


def _docker_image_id(docker: str, image: str) -> str:
    result = subprocess.run(
        [docker, "image", "inspect", image, "--format", "{{.Id}}"],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    image_id = result.stdout.strip()
    if result.returncode != 0 or not image_id.startswith("sha256:"):
        raise RuntimeError(
            f"Docker image {image!r} must already exist locally; automatic pulls are disabled"
        )
    return image_id


def _run_restricted_container(
    scenarios_text: str,
    *,
    image: str,
    runner_path: Path,
    timeout: int,
) -> tuple[str, str, str, list[str]]:
    docker = shutil.which("docker")
    if not docker:
        raise RuntimeError("docker executable was not found")
    image_id = _docker_image_id(docker, image)
    runner_source = runner_path.read_text(encoding="utf-8")
    command = [
        docker,
        "run",
        "--rm",
        "--interactive",
        "--pull=never",
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--pids-limit=64",
        "--memory=256m",
        "--cpus=1.0",
        "--user=65534:65534",
        "--tmpfs=/tmp:rw,noexec,nosuid,size=32m",
        "--hostname=vulntools-lab",
        "--env=PYTHONHASHSEED=0",
        "--label=vulntools.scope=harmless-canary",
        image,
        "python",
        "-B",
        "-c",
        runner_source,
    ]
    result = subprocess.run(
        command,
        input=scenarios_text,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=timeout,
    )
    if result.returncode != 0:
        message = result.stderr.strip()[-2000:]
        raise RuntimeError(f"Restricted Docker canary batch failed with exit {result.returncode}: {message}")
    restrictions = [
        "network=none",
        "read_only_root=true",
        "cap_drop=ALL",
        "no_new_privileges=true",
        "pids_limit=64",
        "memory=256m",
        "cpus=1.0",
        "uid=65534",
        "tmpfs_noexec=true",
        "pull=never",
    ]
    return result.stdout, result.stderr, image_id, restrictions


def _step(
    observation: str,
    action_type: str,
    tool: str,
    input_value: dict[str, Any],
    result: dict[str, Any],
    *,
    blocked: bool = False,
    recovery_strategy: str | None = None,
    evidence: list[str] | None = None,
    decision_basis: str,
) -> dict[str, Any]:
    return {
        "observation": observation,
        "action_type": action_type,
        "tool": tool,
        "input": input_value,
        "result": result,
        "blocked": blocked,
        "recovery_strategy": recovery_strategy,
        "evidence": evidence or [],
        "decision_basis": decision_basis,
    }


def docker_result_to_trajectory(
    scenario: dict[str, Any],
    result: dict[str, Any],
    *,
    image: str,
    image_id: str,
    restrictions: list[str],
    result_path: Path,
    result_line: int,
    batch_id: str,
) -> dict[str, Any]:
    if result.get("scenario_id") != scenario["scenario_id"]:
        raise ValueError("Docker result identity does not match its scenario")
    if result.get("scenario_sha256") != _sha256_bytes(canonical_json(scenario).encode("utf-8")):
        raise ValueError(f"Scenario hash mismatch for {scenario['scenario_id']}")
    if result.get("evidence_digest") != scenario["expected_digest"]:
        raise ValueError(f"Evidence digest mismatch for {scenario['scenario_id']}")
    if result.get("success") is not True:
        raise ValueError(f"Docker canary did not succeed for {scenario['scenario_id']}")
    obstacle = str(scenario["obstacle"])
    expected_blocked = obstacle != "none"
    if result.get("obstacle") != obstacle or result.get("blocked_initial") is not expected_blocked:
        raise ValueError(f"Obstacle evidence mismatch for {scenario['scenario_id']}")
    if result.get("recovery_verified") is not True or result.get("recovered") is not True:
        raise ValueError(f"Obstacle recovery was not verified for {scenario['scenario_id']}")
    runtime = result.get("runtime") or {}
    if runtime.get("container") is not True or runtime.get("network_expected") != "none":
        raise ValueError(f"Docker runtime evidence is incomplete for {scenario['scenario_id']}")
    if runtime.get("uid") != 65534 or runtime.get("gid") != 65534:
        raise ValueError(f"Docker canary did not run as the expected unprivileged identity for {scenario['scenario_id']}")
    if runtime.get("cap_eff") != "0000000000000000" or runtime.get("no_new_privileges") is not True:
        raise ValueError(f"Docker privilege restrictions were not observed for {scenario['scenario_id']}")
    if runtime.get("interfaces") != ["lo"] or runtime.get("root_write_blocked") is not True:
        raise ValueError(f"Docker network/read-only restrictions were not observed for {scenario['scenario_id']}")

    evidence_pointer = f"{result_path.resolve()}#L{result_line}"
    method = METHOD_PROFILES[str(scenario["vulnerability_type"])]
    obstacle_profile = OBSTACLE_PROFILES[obstacle]
    recovery = obstacle_profile["strategy_zh"]
    steps = [
        _step(
            "已确认任务仅针对本地 Docker 内的授权合成 canary，不存在公网或第三方目标。",
            "define_scope",
            "vulntools.docker_trajectory_lab",
            {
                "scenario_id": scenario["scenario_id"],
                "variant": scenario["variant"],
                "canary_sha256": _sha256_bytes(scenario["canary"].encode("utf-8")),
            },
            {
                "status": "accepted",
                "authorized": True,
                "target_scope": scenario["target_scope"],
                "scenario_sha256": result["scenario_sha256"],
            },
            evidence=[evidence_pointer],
            decision_basis="只有授权范围、容器限制和唯一 canary 均明确时才进入测试。",
        ),
        _step(
            f"测试点为{method['test_point_zh']}。待验证假设：{method['hypothesis_zh']}",
            "form_hypothesis",
            "method_profile",
            {
                "method": scenario["vulnerability_type"],
                "method_name_zh": method["name_zh"],
                "test_point_zh": method["test_point_zh"],
            },
            {
                "hypothesis_zh": method["hypothesis_zh"],
                "planned_safe_action_zh": method["safe_action_zh"],
                "success_criteria_zh": method["success_criteria_zh"],
            },
            evidence=[evidence_pointer],
            decision_basis="先固定漏洞类型的可观察假设和成功判据，避免在结果出现后修改标准。",
        ),
        _step(
            f"前置检查识别到阻碍条件“{obstacle_profile['name_zh']}”。{obstacle_profile['assessment_zh']}",
            "assess_obstacle",
            "docker_canary_state_machine",
            {"obstacle": obstacle, "variant": scenario["variant"]},
            {
                "observed": expected_blocked,
                "observation_proof": result["obstacle_observation"],
                "assessment_zh": obstacle_profile["assessment_zh"],
            },
            blocked=expected_blocked,
            recovery_strategy=recovery,
            evidence=[evidence_pointer],
            decision_basis="根据明示前置状态选择恢复分支，不扩大任务目标或改变成功判据。",
        ),
        _step(
            f"处理策略：{recovery}",
            "recover_or_proceed",
            "docker_canary_state_machine",
            {"obstacle": obstacle, "same_canary": True, "same_scope": True},
            {
                "status": "ready",
                "recovery_action": result["recovery_action"],
                "recovery_verified": result["recovery_verified"],
                "recovery_proof": result["obstacle_observation"],
            },
            recovery_strategy=recovery,
            evidence=[evidence_pointer],
            decision_basis="只在恢复动作有容器内证据且仍使用原 canary 时继续。",
        ),
        _step(
            f"{method['safe_action_zh']} 容器观察：{result['observation']}",
            "execute_canary",
            "restricted_docker_container",
            {
                "vulnerability_type": scenario["vulnerability_type"],
                "variant": scenario["variant"],
                "payload_disclosed": False,
            },
            {"status": "passed", "proof": result["proof"]},
            evidence=[evidence_pointer],
            decision_basis="执行动作由类型化方法配置预先确定，仅使用固定合成数据与对照分支。",
        ),
        _step(
            f"将可观察证据与预先定义的成功判据比对：{method['success_criteria_zh']}",
            "verify_evidence",
            "sha256_oracle",
            {
                "expected_digest": scenario["expected_digest"],
                "success_criteria_zh": method["success_criteria_zh"],
            },
            {
                "actual_digest": result["evidence_digest"],
                "matched": True,
                "canary_check_passed": True,
                "recovery_verified": True,
            },
            evidence=[evidence_pointer],
            decision_basis="canary 对照、恢复证据和主机预计算摘要必须同时匹配。",
        ),
        _step(
            "七个阶段均已记录，阻碍已解决，canary 验证成功，任务完成。",
            "complete_task",
            "trajectory_completion_gate",
            {"required_phases": list(CHAIN_PHASES)},
            {
                "all_phases_present": True,
                "obstacle_resolved": True,
                "success_oracle_matched": True,
                "task_completed": True,
            },
            evidence=[evidence_pointer],
            decision_basis="只有阶段完整、恢复成功且证据摘要匹配时才标记任务成功。",
        ),
    ]
    steps[4]["result"]["runtime_evidence"] = runtime

    events = [{
        "run_id": scenario["scenario_id"],
        "timestamp": result["started_at"],
        "type": "container_scenario_started",
        "batch_id": batch_id,
        "image_id": image_id,
    }]
    if result.get("blocked_initial"):
        events.append({
            "run_id": scenario["scenario_id"],
            "timestamp": result["started_at"],
            "type": "declared_obstacle_recovered",
            "obstacle": result["obstacle"],
        })
    events.append({
        "run_id": scenario["scenario_id"],
        "timestamp": result["completed_at"],
        "type": "canary_verified",
        "evidence_digest": result["evidence_digest"],
    })

    trajectory = {
        "schema_version": SCHEMA,
        "task_id": scenario["scenario_id"],
        "category": scenario["category"],
        "vulnerability_type": scenario["vulnerability_type"],
        "requirement_id": CATEGORY_REQUIREMENTS[str(scenario["category"])],
        "task_objective_zh": f"在授权合成 Docker 环境中完成{method['name_zh']}的自动化对照测试。",
        "success_criteria_zh": method["success_criteria_zh"],
        "obstacle_condition": {
            "code": obstacle,
            "name_zh": obstacle_profile["name_zh"],
            "initially_blocked": expected_blocked,
            "assessment_zh": obstacle_profile["assessment_zh"],
            "strategy_zh": recovery,
            "recovery_verified": True,
        },
        "structured_pentest_chain": {
            "schema": "vulntools/observable-pentest-decision-chain/v1",
            "label_zh": "自动化渗透思维链（可观察决策轨迹）",
            "nature": "observable_structured_decision_trace",
            "phase_order": list(CHAIN_PHASES),
            "phase_count": len(CHAIN_PHASES),
            "method_profile": method,
            "obstacle_profile": obstacle_profile,
            "complete": True,
            "task_success_required": True,
            "task_success": True,
        },
        "environment": {
            "kind": "docker_canary_lab",
            "authorized": True,
            "scope": "local synthetic canary only; no public or third-party target",
            "image": image,
            "image_id": image_id,
            "batch_id": batch_id,
            "restrictions": restrictions,
            "production_isolation_attested": False,
        },
        "precondition": "Docker daemon is local and available; image exists locally; the run is network-disabled and limited to built-in harmless canaries.",
        "steps": steps,
        "success": True,
        "blocked": False,
        "recovery_strategy": recovery,
        "evidence": [{
            "path": str(result_path.resolve()),
            "line": result_line,
            "scenario_sha256": result["scenario_sha256"],
            "evidence_digest": result["evidence_digest"],
        }],
        "runtime_events": events,
        "created_at": result["started_at"],
        "completed_at": result["completed_at"],
        "is_simulated": False,
        "execution_ready": True,
        "real_vulnerability_verified": False,
        "synthetic_scenario": True,
        "outcome_scope": "docker_lab_canary_only",
        "contains_internal_reasoning": False,
        "chain_complete": True,
        "completion": {
            "required_phases": list(CHAIN_PHASES),
            "all_phases_present": True,
            "obstacle_resolved": True,
            "success_oracle_matched": True,
            "task_completed": True,
        },
    }
    return validate_trajectory(trajectory)


def generate_docker_trajectories(
    store: Store,
    output: str | Path,
    *,
    count: int = 3000,
    seed: str = "vulntools-docker-lab-v1",
    image: str = "python:3.12",
    timeout: int = 300,
) -> dict[str, Any]:
    if type(timeout) is not int or timeout < 10:
        raise ValueError("timeout must be an integer of at least 10 seconds")
    directory = Path(output).resolve()
    directory.mkdir(parents=True, exist_ok=True)
    runner_path = Path(__file__).resolve().parents[1] / "deployment" / "docker_trajectory_lab.py"
    if not runner_path.is_file():
        raise RuntimeError(f"Docker trajectory runner is missing: {runner_path}")

    scenarios = build_docker_scenarios(count, seed)
    scenarios_text = "".join(canonical_json(item) + "\n" for item in scenarios)
    scenario_path = directory / "scenario-input.jsonl"
    result_path = directory / "container-results.jsonl"
    stderr_path = directory / "container-stderr.txt"
    trajectory_path = directory / "trajectories.jsonl"
    scenario_path.write_text(scenarios_text, encoding="utf-8")
    started_at = now()
    stdout, stderr, image_id, restrictions = _run_restricted_container(
        scenarios_text, image=image, runner_path=runner_path, timeout=timeout
    )
    result_path.write_text(stdout, encoding="utf-8")
    stderr_path.write_text(stderr, encoding="utf-8")
    result_lines = [line for line in stdout.splitlines() if line.strip()]
    if len(result_lines) != len(scenarios):
        raise RuntimeError(f"Docker returned {len(result_lines)} results for {len(scenarios)} scenarios")
    results = [json.loads(line) for line in result_lines]
    runner_sha256 = _sha256_file(runner_path)
    batch_id = "docker-batch:" + _sha256_bytes(
        f"{image_id}:{runner_sha256}:{_sha256_bytes(scenarios_text.encode('utf-8'))}".encode("utf-8")
    )[:24]
    trajectories = [
        docker_result_to_trajectory(
            scenario,
            result,
            image=image,
            image_id=image_id,
            restrictions=restrictions,
            result_path=result_path,
            result_line=index + 1,
            batch_id=batch_id,
        )
        for index, (scenario, result) in enumerate(zip(scenarios, results))
    ]
    trajectory_path.write_text(
        "".join(canonical_json(item) + "\n" for item in trajectories), encoding="utf-8"
    )
    imported = import_trajectories(store, trajectory_path)
    dataset = export_trajectories(store, directory / "dataset")
    completed_at = now()
    type_counts = dict(sorted(Counter(item["vulnerability_type"] for item in trajectories).items()))
    obstacle_counts = dict(sorted(Counter(item["obstacle"] for item in results).items()))
    manifest = {
        "schema": "vulntools/docker-trajectory-batch/v1",
        "batch_id": batch_id,
        "created_at": completed_at,
        "started_at": started_at,
        "completed_at": completed_at,
        "image": image,
        "image_id": image_id,
        "restrictions": restrictions,
        "runner": {
            "path": str(runner_path),
            "sha256": runner_sha256,
        },
        "counts": {
            "requested": count,
            "executed": len(results),
            "succeeded": sum(item["success"] is True for item in results),
            "imported": imported["saved"],
            "technical_vulnerability": sum(item["category"] == "technical_vulnerability" for item in trajectories),
            "business_logic": sum(item["category"] == "business_logic" for item in trajectories),
        },
        "vulnerability_types": type_counts,
        "obstacles": obstacle_counts,
        "artifacts": {
            "scenario_input": {"path": scenario_path.name, "sha256": _sha256_file(scenario_path)},
            "container_results": {"path": result_path.name, "sha256": _sha256_file(result_path)},
            "container_stderr": {"path": stderr_path.name, "sha256": _sha256_file(stderr_path)},
            "trajectories": {"path": trajectory_path.name, "sha256": _sha256_file(trajectory_path)},
            "dataset": dataset,
        },
        "contains_internal_reasoning": False,
        "real_world_vulnerabilities_verified": 0,
        "scope": "Executed Docker canaries in synthetic authorized scenarios only.",
    }
    manifest_path = directory / "docker-run-manifest.json"
    manifest_path.write_text(canonical_json(manifest) + "\n", encoding="utf-8")
    return {**manifest, "manifest": str(manifest_path), "database_summary": store.trajectory_summary()}
