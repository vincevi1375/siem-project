from schema import *
from typing import Any
from google.cloud import logging
from datetime import datetime, timezone
import requests
import hashlib
import json

class GCPSource(Source):
    """
    first source interface dedicated to GCP
    GCPSource inherits from Source ABC
    """
    def __init__(self, project_id: str, client = None): # doing this prevents us from hardcoing project_id, allowing for flexibility for tetsing other GCP projects and mocks for tests
        """
        personal note, get into the habit of developing for flexibility 
        always assume that someone else will use your code with different
        configurations, keys, and tuning than you. this is open-source after all
        key word: portability
        """
        self.project_id = project_id
        self.client = client if client is not None else logging.Client(project = project_id) # if the client parameter is filled when GCPSource is instantiated, use the input (this is only the case for tests), if it is not filled, we default to the live production client (basically do not fill this in yourself unless you're testing)
        self.base_filter = f"logName=\"projects/{self.project_id}/logs/cloudaudit.googleapis.com%2Factivity\""

    def batch_pull(self, limit: int = 100, checkpoint: str | None = None) -> BatchResults:
        if checkpoint is None:
            query = self.base_filter
        else:
            query = self.base_filter + f" AND timestamp >= \"{checkpoint}\"" # format checkpoint as RFC3339
        results = list(self.client.list_entries(filter_ = query, order_by = logging.ASCENDING, max_results = limit)) # returns only 100 LogEntrys
        if results:
            next_checkpoint = results[-1].timestamp.isoformat() # this is our checkpoint builder, basically we take the last event from the list above (newest event), we pull the timestamp field from that event and format it to RFC3339 as without formatting it returns a non-acceptable string
        else:
            next_checkpoint = checkpoint
        raw_events = [result.to_api_repr() for result in results] # run to_api-repr on the current result for every result inside of results - convert every LogEntry object to JSON, list em
        return BatchResults(raw_events, next_checkpoint)
    
class GCPNormalizer(Normalizer):
    """
    so, why doesn't this need an __init__? thats because nothing about this 
    subclass creation is different from the abstract it inherits from.
    we needed an __init__ for source subclass creation as there were attributes
    that the abstract class it inherited from did not have.

    still not a fan of properties
    """

    @property 
    def source(self):
        return LogSource.GCP_AUDIT
    
    def extract_stable_id(self, raw_event: dict ) -> str | None: 
        """
        use .get() when accessing keys from a dict, especially here if no stable ID is returned,
        if we directly accessed it dict[...] and no stable ID was there = crash
        """
        return raw_event.get("insertId")
        
    def make_event_id(self, raw_event: dict) -> str:
        """
        handy hash: if an ID doesn't exist on a GCP log (this would never happen, just edge case)
        we need an identifier that is unique while being deterministic. this means that the same raw event
        must always produce the same id for every run, forever and ever. with this being the case we need...
        a cryptographic hash. hashlib must be used here for multiple reasons 1. its deterministic,
        2. it gives stable hashes (sha256 here). in order for us to actually hash the entire raw event it 
        cannot be a dictionary so we use json.dumps to turn it into a json string (bytes, hashlib wants bytes)
        that is then sorted by keys. the sort is to ensure that the same dictionary always seralizies identically 
        regardless of the key order it arrives it. and then finally that sorted json string is encoded into
        bytes for the hash input.

        also, the reason why we slap a prefix on all these IDs is because we want to ensure that there is 
        no possibility for duplicates across differing data sources e.g. gcp_audit-<enter_id> vs okta-<enter_id>
        unlikely that this happens, however it is an edge case. better to leave no stone unturned
        """
        stable_id = self.extract_stable_id(raw_event)
        if stable_id is None:
            handy_hash = hashlib.sha256(json.dumps(raw_event, sort_keys=True).encode("utf-8")).hexdigest()
            return f"{self.source.value}-{handy_hash}"
        else:
            return f"{self.source.value}-{stable_id}" 

    def normalize_batch(self, raw_events: list[dict], ingest_time: datetime) -> NormalizeResults:
        """
        yes, this function needs to be optimized with a helper, yes its an eye-sore, will address later
        the large one-liners are technically optional fields if considering bare-minimum
        however these fields are supposed to model Google SecOps UDM
        """
        success = []
        fail = []
        for raw in raw_events:
            try:
                auth_info = raw.get("protoPayload", {}).get("authorizationInfo", [])
                principal = raw.get("protoPayload", {}).get("authenticationInfo", {}).get("principalEmail")
                resource_id = raw.get("protoPayload", {}).get("resourceName")
                event = Event(
                    event_id = self.make_event_id(raw),             
                    event_time = raw.get("timestamp"),
                    ingest_time = ingest_time, 
                    source = self.source,      
                    action = raw["protoPayload"]["methodName"],
                    outcome = Outcome.DENIED if any(entry.get("granted") is False for entry in auth_info) else (Outcome.SUCCESS if auth_info else Outcome.UNKNOWN), # account for non-empty error status being mapped to FAILURE, will cover in future commit
                    actor = Actor(type = ActorType.SYSTEM if principal is None else (ActorType.SERVICE_ACCOUNT if principal.endswith("gserviceaccount.com") else ActorType.USER), id = principal, display_name = None),
                    target = Target(type = None, id = resource_id, display_name = None),
                    description = None, #Nothing for now. Future update will include AI Triage of Log (via Claude Haiku)
                    raw = raw,
                )          
                success.append(event)
            except Exception as e:
                fail.append(FailedEvent(raw=raw, error=str(e)))
        return NormalizeResults(events = success, failures = fail)