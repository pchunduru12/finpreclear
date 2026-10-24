# FinPreclear private demo

This is an **access-restricted synthetic demonstration, not a beta**. Human presenters supply all fictional scenarios and manually select simulation results. No model is trained or evaluated; no bank integration or payment action is executed. The UI must disclose **STUB / SIMULATION — NOT A TRAINED MODEL** on every result.

No model-drafted or red-team-generator text may enter a training/evaluation corpus. The original seven operational agents and the orchestrator remain authoritative. Do not open project gates.

Time-box demo development to 2–4 weeks. Assign the human security engineer immediately; demo work must not delay approximately six human weeks of template authoring. All actual training/evaluation templates must be written from scratch by humans.
## Local-only run instructions

Choose a random passphrase (minimum 24 characters) in your own shell environment; do not commit it, share it or use a real bank credential:

```bash
export FINPRECLEAR_DEMO_PASSWORD='replace-with-a-locally-generated-secret-at-least-24-chars'
python -m scripts.demo_server --port 8765
```

Open `http://127.0.0.1:8765/` on the same computer. Username: `demo`; password: your local environment variable. No external hosting, reverse proxy, tunnel or public access. Local HTTP Basic authentication is only suitable for the protected loopback demo, not a bank network. The presenter must type original fictional scenarios and select an obviously simulated verdict.
