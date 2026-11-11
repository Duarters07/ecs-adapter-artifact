"""Phase 1c - turning verified proposals into adapters.

Only the adapter is ever trained. The base model stays frozen and reproducible,
which is what makes a rollback possible and what keeps the deployed artefact
describable as "one 4.7 GB base plus two ~100 MB adapters".
"""
