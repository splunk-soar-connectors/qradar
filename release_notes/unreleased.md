**Unreleased**

* Validate and clamp scheduled ingestion checkpoints to the current poll boundary.
* Propagate HTML response failures as scalar action errors during offense and event ingestion.
* Skip malformed offense records without aborting the remaining ingestion batch or corrupting its checkpoint.
* Allow successful reference-set and close-offense responses to omit the optional Content-Type header.
* Bound QRadar API requests with the connector's existing 30-second network timeout.
* Return a clean action error when QRadar sends a non-object JSON error response.
* Stop Ariel result pagination when an additional page makes no forward progress.
* Reject non-object Ariel search creation and status responses with a clean action error.
* Preserve explicit requested and checkpointed event time bounds in alternate Ariel queries.
