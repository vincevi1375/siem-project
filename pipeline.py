from schema import *
from typing import Any
from google.cloud import logging
import requests
import itertools

class GCPSource(Source):
    """
    first source interface dedicated to GCP
    GCPSource inherits from Source ABC
    """
    def __init__(self, project_id: str): # doing this prevents us from hardcoing project_id, allowing for flexibility to tetsing other GCP projects and mocks for tests
        self.project_id = project_id
        self.client = logging.Client(project=project_id)            # creating a gcp client requires TLS handshake, so storing the client allows for reuse instead of making a new one each batch_pull
        self.base_filter = f"logName=\"projects/{self.project_id}/logs/cloudaudit.googleapis.com%2Factivity\""

    def batch_pull(self, limit: int = 100, checkpoint: Any | None = None) -> BatchResults:
        if checkpoint is None:
            query = self.base_filter
        else:
            query = self.base_filter + f" AND timestamp >= \"{checkpoint}\"" # format checkpoint as RFC3339
        results = list(self.client.list_entries(filter_ = query, order_by = logging.ASCENDING, max_results = limit)) # returns only 100 LogEntrys
        if results:
            next_checkpoint = results[-1].timestamp
        else:
            next_checkpoint = checkpoint
        raw_events = [result.to_api_repr() for result in results] # run to_api-repr on the current result for every result inside of results - convert every LogEntry object to JSON, list em
        return BatchResults(raw_events, next_checkpoint)