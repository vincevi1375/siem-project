from gcp_src import *

# arrange, act, assert

class FakeLogObject():
    def __init__(self, timestamp: datetime, api_repr: dict):
        self.timestamp = timestamp
        self._api_repr = api_repr 

    def to_api_repr(self) -> dict:
        return self._api_repr
        
class FakeClient:
    def __init__(self, entries: list):
        self._entries = entries
        self.received_filter = None

    def list_entries(self, filter_ = None, order_by = None, max_results = None) -> list:
        self.received_filter = filter_
        return self._entries 

def test_batch_pull_functionality():
    """
    self explanatory
    """
    entries = [
        FakeLogObject(timestamp=datetime(2026, 6, 26, 20, 0, 0, tzinfo=timezone.utc), api_repr={"insertId": "a"}),
        FakeLogObject(timestamp=datetime(2026, 6, 26, 20, 5, 0, tzinfo=timezone.utc), api_repr={"insertId": "b"}),
        FakeLogObject(timestamp=datetime(2026, 6, 26, 20, 10, 0, tzinfo=timezone.utc), api_repr={"insertId": "c"}),
    ]
    fake_client = FakeClient(entries)
    source = GCPSource("test-project", client=fake_client)
    result = source.batch_pull(limit=10)

    assert len(result.events) == 3
    assert result.events[0] == entries[0].to_api_repr() #don't reach directly to the private attribute, use the method to return the field instead
    assert result.next_checkpoint == entries[-1].timestamp.isoformat()
    assert all(isinstance(e, dict) for e in result.events)

def test_checkpoint_and_query():
    """
    testing to ensure that when a batch is empty, the next_checkpoint remains as the original checkpoint. 
    if this control did not exist, logs would definitely be lost or reprocessed

    testing to ensure that query is rebuilt with the timestamp clause when provided with a checkpoint
    also testing the inverse of above ^
    """
    entries = []
    fake_client = FakeClient(entries)
    source = GCPSource("test-project", client=fake_client)
    result = source.batch_pull(checkpoint = "2026-06-26T20:00:00+00:00")

    assert "timestamp >=" in fake_client.received_filter
    assert result.next_checkpoint == "2026-06-26T20:00:00+00:00"

    source.batch_pull()

    assert "timestamp >=" not in fake_client.received_filter

def test_normalize_batch_execution():
    raw_event = {
        "insertId": "abc123",
        "timestamp": "2026-06-28T01:38:46.664569Z",
        "protoPayload": {
            "methodName": "google.iam.admin.v1.CreateServiceAccount",
            "authenticationInfo": {"principalEmail": "user@example.com"},
            "authorizationInfo": [{"granted": True}],
            "resourceName": "projects/test-project",
        }
    }
    normalizer = GCPNormalizer()
    ingest_time = datetime(2026, 6, 28, 1, 41, 0, tzinfo=timezone.utc)

    result = normalizer.normalize_batch([raw_event], ingest_time)

    assert len(result.events) == 1
    assert len(result.failures) == 0
    event = result.events[0]
    assert event.event_id == "gcp_audit-abc123"
    assert event.action == "google.iam.admin.v1.CreateServiceAccount"        
    assert event.outcome == Outcome.SUCCESS           
    assert event.actor.type == ActorType.USER    
    assert event.actor.id == "user@example.com"          
    assert event.target.id == "projects/test-project"         
    
def test_service_account_and_denied():
    raw_event = {
        "insertId": "abc123",
        "timestamp": "2026-06-28T01:38:46.664569Z",
        "protoPayload": {
            "methodName": "google.iam.admin.v1.CreateServiceAccount",
            "authenticationInfo": {"principalEmail": "user@gserviceaccount.com"},
            "authorizationInfo": [{"granted": False}],
            "resourceName": "projects/test-project",
        }
    }
    normalizer = GCPNormalizer()
    ingest_time = datetime(2026, 6, 28, 1, 41, 0, tzinfo=timezone.utc)

    result = normalizer.normalize_batch([raw_event], ingest_time)

    assert len(result.events) == 1
    assert len(result.failures) == 0
    event = result.events[0]
    assert event.event_id == "gcp_audit-abc123"
    assert event.action == "google.iam.admin.v1.CreateServiceAccount"        
    assert event.outcome == Outcome.DENIED          
    assert event.actor.type == ActorType.SERVICE_ACCOUNT        
    assert event.actor.id == "user@gserviceaccount.com"          
    assert event.target.id == "projects/test-project"     

def test_system_event():
    raw_event = {
        "insertId": "abc123",
        "timestamp": "2026-06-28T01:38:46.664569Z",
        "protoPayload": {
            "methodName": "google.iam.admin.v1.CreateServiceAccount",
            "authenticationInfo": {},
            "authorizationInfo": [{"granted": False}],
            "resourceName": "projects/test-project",
        }
    }
    normalizer = GCPNormalizer()
    ingest_time = datetime(2026, 6, 28, 1, 41, 0, tzinfo=timezone.utc)

    result = normalizer.normalize_batch([raw_event], ingest_time)

    assert len(result.events) == 1
    assert len(result.failures) == 0
    event = result.events[0]
    assert event.event_id == "gcp_audit-abc123"
    assert event.action == "google.iam.admin.v1.CreateServiceAccount"        
    assert event.outcome == Outcome.DENIED           
    assert event.actor.type == ActorType.SYSTEM      
    assert event.actor.id == None          
    assert event.target.id == "projects/test-project"     

def test_malformed_event():
    raw_event = {
        "insertId": "abc123",
        "timestamp": "2026-06-28T01:38:46.664569Z",
        "protoPayload": {
            "authenticationInfo": {},
            "authorizationInfo": [{"granted": False}],
            "resourceName": "projects/test-project",
        }
    }
    normalizer = GCPNormalizer()
    ingest_time = datetime(2026, 6, 28, 1, 41, 0, tzinfo=timezone.utc)

    result = normalizer.normalize_batch([raw_event], ingest_time)

    assert len(result.events) == 0
    assert len(result.failures) == 1

