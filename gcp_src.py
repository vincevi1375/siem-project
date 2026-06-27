from schema import *
from typing import Any
from google.cloud import logging
from datetime import datetime, timezone
import requests
import itertools

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