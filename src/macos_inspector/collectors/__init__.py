from .application_trust import ApplicationTrustCollector
from .background_items import BackgroundItemsCollector
from .browser_artifacts import BrowserArtifactsCollector
from .ioc import IOCCollector
from .persistence import PersistenceCollector
from .privacy import PrivacyCollector
from .network import NetworkCollector
from .system_extensions import SystemExtensionsCollector
from .security import SecurityControlsCollector

COLLECTORS = {
    ApplicationTrustCollector.collector_id: ApplicationTrustCollector,
    BackgroundItemsCollector.collector_id: BackgroundItemsCollector,
    BrowserArtifactsCollector.collector_id: BrowserArtifactsCollector,
    IOCCollector.collector_id: IOCCollector,
    PersistenceCollector.collector_id: PersistenceCollector,
    PrivacyCollector.collector_id: PrivacyCollector,
    NetworkCollector.collector_id: NetworkCollector,
    SystemExtensionsCollector.collector_id: SystemExtensionsCollector,
    SecurityControlsCollector.collector_id: SecurityControlsCollector,
}
