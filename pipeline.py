from gcp_src import *
from pathlib import Path
import random
import time
from dotenv import load_dotenv; load_dotenv()

class FileSink(Sink):
    def __init__(self, path: str):
        self.path = path
    
    def write(self, records: list[dict]) -> None:
        with open(self.path, "a") as f: # auto open auto close
            for record in records:
                f.write(json.dumps(record) + "\n") 









source = GCPSource("siem-project-500620")
result = source.batch_pull(limit = 5)

print(f"raw events pulled: {len(result.events)}")          # <-- did the pull get anything?
print(f"checkpoint: {result.next_checkpoint}")

normalizer = GCPNormalizer()
ingest_time = datetime.now(timezone.utc)
final = normalizer.normalize_batch(result.events, ingest_time)

print(f"successes: {len(final.events)}")
print(f"failures: {len(final.failures)}")
if final.events:
    print("first event:", final.events[0])
if final.failures:
    print("first failure error:", final.failures[0].error)

source = GCPSource("siem-project-500620")
normalizer = GCPNormalizer()
fail_sink = FileSink()
success_sink = FileSink()

def write_checkpoint(file_path, checkpoint):
        Path(file_path).parent.mkdir(parents=True, exist_ok=True)
        with open(file_path, "w") as f:
            f.write(json.dumps(checkpoint))

def checkpoint_read(file_path):
    if Path(file_path).exists():
        with open(file_path, "r") as f:
            checkpoint = json.load(f)
        return checkpoint
    return None 

def write_to_dead_letter(file_path, fails, errors, stage):
        Path(file_path).parent.mkdir(parents=True, exist_ok=True)
        with open(file_path, "a") as f:
            for fail in fails:
                entry = {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "stage": stage,
                    "error": errors,
                    "data": fail,
                }
                f.write(json.dumps(entry) + "\n")



def write_with_retry(sink, records, dead_letter, max_retries=5):
    for retry in range(max_retries):
        try:
            sink.write(records)
            return
        except TransientSinkError:
            if retry == max_retries -1:
                break
            wait = min(2 ** retry, 10) + random.uniform(0, 0.5)
            time.sleep(wait)
        except PermanentSinkError as e:
            write_to_dead_letter(dead_letter, records, str(e), "sink")
            return
    raise RuntimeError("Sink was never reached after all retry attempts - stopping")

source = GCPSource("siem-project-500620")
normalizer = GCPNormalizer()
fail_sink = FileSink()
success_sink = FileSink()

checkpoint = checkpoint_read("checkpoints/gcp.json")
while True:
    batch = source.batch_pull(limit = 100, checkpoint = checkpoint)
    ingest_time = datetime.now(timezone.utc)
    batch_norm = normalizer.normalize_batch(batch.events, ingest_time)
    # batch_norm.failures -dead letter
    # formatter
    writer = write_with_retry()
    success = write_checkpoint("checkpoints/gcp.json", batch.next_checkpoint)
    checkpoint = batch.next_checkpoint 

