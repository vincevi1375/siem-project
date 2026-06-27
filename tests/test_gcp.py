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


    

