"""FinGuard data pipeline: templates -> examples -> teacher labels -> splits -> dataset card.

Every stage records provenance so a model-risk reviewer can trace each training row back
to the template, author, teacher model and filters that produced it.
"""
