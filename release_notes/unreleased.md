**Unreleased**

* Validate and clamp scheduled ingestion checkpoints to the current poll boundary.
* Propagate HTML response failures as scalar action errors during offense and event ingestion.
* Skip malformed offense records without aborting the remaining ingestion batch or corrupting its checkpoint.
* Allow successful reference-set and close-offense responses to omit the optional Content-Type header.
