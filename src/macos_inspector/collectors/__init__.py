from .application_trust import ApplicationTrustCollector
from .accounts_access import AccountsAccessCollector
from .background_items import BackgroundItemsCollector
from .browser_artifacts import BrowserArtifactsCollector
from .ioc import IOCCollector
from .live_triage import LiveTriageCollector
from .persistence import PersistenceCollector
from .privacy import PrivacyCollector
from .network import NetworkCollector
from .osint_intelligence import OSINTIntelligenceCollector
from .vulnerability_exposure import VulnerabilityExposureCollector
from .yara_rules import YARARulesCollector
from .management_profiles import ManagementProfilesCollector
from .system_extensions import SystemExtensionsCollector
from .security import SecurityControlsCollector

COLLECTORS = {
    AccountsAccessCollector.collector_id: AccountsAccessCollector,
    ApplicationTrustCollector.collector_id: ApplicationTrustCollector,
    BackgroundItemsCollector.collector_id: BackgroundItemsCollector,
    BrowserArtifactsCollector.collector_id: BrowserArtifactsCollector,
    IOCCollector.collector_id: IOCCollector,
    LiveTriageCollector.collector_id: LiveTriageCollector,
    PersistenceCollector.collector_id: PersistenceCollector,
    PrivacyCollector.collector_id: PrivacyCollector,
    NetworkCollector.collector_id: NetworkCollector,
    OSINTIntelligenceCollector.collector_id: OSINTIntelligenceCollector,
    VulnerabilityExposureCollector.collector_id: VulnerabilityExposureCollector,
    YARARulesCollector.collector_id: YARARulesCollector,
    ManagementProfilesCollector.collector_id: ManagementProfilesCollector,
    SystemExtensionsCollector.collector_id: SystemExtensionsCollector,
    SecurityControlsCollector.collector_id: SecurityControlsCollector,
}

LOCAL_COLLECTORS = tuple(
    collector_id for collector_id, collector in COLLECTORS.items()
    if not collector.external_network
)
