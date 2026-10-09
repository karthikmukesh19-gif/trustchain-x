# datasets/

Reserved for external security datasets (for example a labelled benchmark
for the evaluation described in `docs/research-validation.md`). Nothing is
stored here.

The dataset the platform builds from its own analysis results (Phase 10) is
kept in MongoDB (`datasets`, `dataset_records`, `dataset_quality`), not in
this directory. Any external dataset placed here should be recorded with its
source, version, hash, licence and provenance before it is used.
