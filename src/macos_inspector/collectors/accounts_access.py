from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict, dataclass

from .base import Collector
from macos_inspector.core.models import Evidence, Finding, Severity


DISABLED_SHELLS = {"", "/usr/bin/false", "/bin/false", "/usr/sbin/nologin"}


@dataclass(frozen=True)
class AccountRecord:
    name: str
    uid: int
    gid: int | None
    home: str
    shell: str


def parse_user_records(output: str) -> tuple[AccountRecord, ...]:
    """Parse dscacheutil user records while intentionally discarding password fields."""
    records: list[AccountRecord] = []
    for block in output.split("\n\n"):
        values: dict[str, str] = {}
        for line in block.splitlines():
            key, separator, value = line.partition(":")
            if separator:
                values[key.strip().lower()] = value.strip()
        if not values.get("name") or "uid" not in values:
            continue
        try:
            uid = int(values["uid"])
            gid = int(values["gid"]) if values.get("gid") else None
        except ValueError:
            continue
        records.append(AccountRecord(
            name=values["name"], uid=uid, gid=gid,
            home=values.get("dir", ""), shell=values.get("shell", ""),
        ))
    return tuple(sorted(records, key=lambda record: (record.uid, record.name.lower())))


def parse_group_members(output: str) -> tuple[str, ...]:
    members: set[str] = set()
    for line in output.splitlines():
        key, separator, value = line.partition(":")
        if separator and key.strip().lower() == "users":
            members.update(item for item in value.split() if item)
    return tuple(sorted(members, key=str.lower))


def regular_accounts(records: tuple[AccountRecord, ...]) -> tuple[AccountRecord, ...]:
    return tuple(
        record for record in records
        if 500 <= record.uid < 65534
    )


def account_anomalies(records: tuple[AccountRecord, ...], administrators: tuple[str, ...]) -> dict[str, object]:
    regular = regular_accounts(records)
    regular_names = {record.name for record in regular}
    uid_members: dict[int, list[str]] = defaultdict(list)
    for record in regular:
        uid_members[record.uid].append(record.name)
    duplicate_uids = {
        str(uid): tuple(sorted(names, key=str.lower))
        for uid, names in uid_members.items() if len(names) > 1
    }
    low_uid_interactive = tuple(
        record for record in records
        if 0 < record.uid < 500
        and record.name.lower() not in {"daemon", "guest", "nobody"}
        and record.home.startswith("/Users/")
        and record.shell not in DISABLED_SHELLS
    )
    unlisted_administrators = tuple(
        member for member in administrators
        if member != "root" and member not in regular_names
    )
    return {
        "duplicate_uids": duplicate_uids,
        "low_uid_interactive": tuple(asdict(record) for record in low_uid_interactive),
        "unlisted_administrators": unlisted_administrators,
    }


class AccountsAccessCollector(Collector):
    collector_id = "accounts-access"
    title = "Accounts & administrative access"

    def collect(self) -> list[Finding]:
        user_result = self.runner.run(("dscacheutil", "-q", "user"))
        group_result = self.runner.run(("dscacheutil", "-q", "group", "-a", "name", "admin"))
        users_ok = user_result.returncode == 0 and not user_result.timed_out
        group_ok = group_result.returncode == 0 and not group_result.timed_out
        records = parse_user_records(user_result.stdout) if users_ok else ()
        administrators = parse_group_members(group_result.stdout) if group_ok else ()
        return [
            self._inventory_finding(user_result, records, users_ok),
            self._administrators_finding(group_result, administrators, group_ok),
            self._anomalies_finding(user_result, group_result, records, administrators, users_ok and group_ok),
        ]

    def _inventory_finding(self, result, records: tuple[AccountRecord, ...], accessible: bool) -> Finding:
        visible = regular_accounts(records)
        if accessible:
            severity, status = Severity.INFORMATIONAL, "Observed"
            observed = f"{len(visible)} regular account record(s) are visible: " + (
                ", ".join(record.name for record in visible) if visible else "none"
            ) + "."
        else:
            severity, status = Severity.INFORMATIONAL, "Unknown"
            observed = result.stderr or f"Command returned exit status {result.returncode}."
        return Finding(
            finding_id="ACCOUNTS-INVENTORY", category="Accounts & Access",
            title="Regular account inventory", severity=severity, status=status,
            description="Inventories visible regular account records while deliberately excluding password fields and authentication material.",
            why_it_matters="Unexpected local or directory-backed accounts can provide persistent access to the host.",
            what_was_checked=result.command,
            expected_result="Every visible regular account is attributable to an authorized person or service.",
            observed_result=observed,
            recommendation="Validate account ownership and purpose against the approved asset and identity inventory.",
            evidence=(Evidence("sanitized_account_inventory", result.command, {
                "returncode": result.returncode, "timed_out": result.timed_out,
                "accounts": tuple(asdict(record) for record in visible),
                "sensitive_fields_retained": False,
            }),),
            commands_used=(result.command,),
            mitre_attack=("T1087.001 - Account Discovery: Local Account",),
            references=("https://support.apple.com/guide/mac-help/add-a-user-or-group-mchl3e281fc9/mac",),
        )

    def _administrators_finding(self, result, administrators: tuple[str, ...], accessible: bool) -> Finding:
        if accessible:
            severity, status = Severity.INFORMATIONAL, "Observed"
            observed = f"{len(administrators)} administrator group member(s) are visible: " + (
                ", ".join(administrators) if administrators else "none"
            ) + "."
        else:
            severity, status = Severity.INFORMATIONAL, "Unknown"
            observed = result.stderr or f"Command returned exit status {result.returncode}."
        return Finding(
            finding_id="ACCOUNTS-ADMINISTRATORS", category="Accounts & Access",
            title="Administrative group membership", severity=severity, status=status,
            description="Lists the visible members of the local admin group without testing credentials or changing membership.",
            why_it_matters="Administrator accounts can change security controls, install software, and access protected host data.",
            what_was_checked=result.command,
            expected_result="Every administrator group member is authorized and necessary.",
            observed_result=observed,
            recommendation="Review administrator membership against the least-privilege policy and investigate unexpected members.",
            evidence=(Evidence("administrator_membership", result.command, {
                "returncode": result.returncode, "timed_out": result.timed_out,
                "members": administrators,
            }),),
            commands_used=(result.command,),
            mitre_attack=("T1098 - Account Manipulation",),
            references=("https://support.apple.com/guide/mac-help/change-users-groups-settings-mtusr001/mac",),
        )

    def _anomalies_finding(self, user_result, group_result, records, administrators, accessible: bool) -> Finding:
        anomalies = account_anomalies(records, administrators) if accessible else {
            "duplicate_uids": {}, "low_uid_interactive": (), "unlisted_administrators": (),
        }
        anomaly_count = (
            len(anomalies["duplicate_uids"])
            + len(anomalies["low_uid_interactive"])
            + len(anomalies["unlisted_administrators"])
        )
        if not accessible:
            severity, status = Severity.INFORMATIONAL, "Unknown"
            observed = user_result.stderr or group_result.stderr or "The account inventory was incomplete."
        elif anomaly_count:
            severity, status = Severity.MEDIUM, "Review"
            observed = (
                f"Observed {len(anomalies['duplicate_uids'])} duplicated regular UID(s), "
                f"{len(anomalies['low_uid_interactive'])} low-UID interactive account(s), and "
                f"{len(anomalies['unlisted_administrators'])} administrator(s) absent from the regular inventory."
            )
        else:
            severity, status = Severity.INFORMATIONAL, "Pass"
            observed = "No targeted account-record anomaly was observed."
        commands = (user_result.command, group_result.command)
        return Finding(
            finding_id="ACCOUNTS-ANOMALIES", category="Accounts & Access",
            title="Account identity anomalies", severity=severity, status=status,
            description="Checks for duplicate regular UIDs, interactive low-UID home accounts, and administrators missing from the regular account inventory.",
            why_it_matters="Identity-record inconsistencies can indicate hidden access, unsafe provisioning, or account manipulation.",
            what_was_checked="; ".join(commands),
            expected_result="Regular account UIDs are unique and all non-root administrators appear in the regular account inventory.",
            observed_result=observed,
            recommendation="Correlate anomalies with Directory Services, MDM, and asset records before changing any account.",
            evidence=(Evidence("account_anomaly_summary", "; ".join(commands), anomalies),),
            commands_used=commands,
            mitre_attack=("T1098 - Account Manipulation", "T1136.001 - Create Account: Local Account"),
            references=("https://support.apple.com/guide/mac-help/change-users-groups-settings-mtusr001/mac",),
        )
