"""Pytest bootstrap.

Ensures the test suite always runs in DEMO MODE regardless of any local
backend/.env: an empty NVIDIA_API_KEY in the environment wins over .env
(load_dotenv never overrides an existing variable), so no test ever performs
real NVIDIA calls or depends on a developer's key.
"""
import os

os.environ["NVIDIA_API_KEY"] = ""
