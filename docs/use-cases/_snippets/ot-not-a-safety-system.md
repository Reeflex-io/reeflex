!!! warning "What Reeflex does not claim here"

    - Reeflex is **not a safety system** and must never be described as one. Safety functions are SIL-rated hardware / safety-PLC logic (IEC 61508, ISO 13849). Reeflex is a defence-in-depth layer **above** the safety PLC, at the agent boundary: it decides whether the agent may **issue** the command. The SIS stays the last line.
    - **Supervisory level only.** Setpoints, modes, recipes, firmware, missions — not the control loop (milliseconds).
    - **Verdict ≠ outcome.** Reeflex records the decision and the *declared* magnitude; it does not read sensors. Attest says so, as it does for IT evidence (received vs occurred).
    - `envelope_fraction` and `safety_function` are the **adapter's** declarations. A wrong safe range in a mapping is a wrong verdict — mapping files are controlled documents, and the docs say so.
