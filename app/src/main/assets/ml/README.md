This directory is reserved for the trained model artifact.

The app expects active-model.json in this directory. Do not create an empty, random, synthetic or hand-written model to make the UI say AI is active. Generate it with tools/train_multiview_model.py from a licensed and documented feature corpus, review its recorded validation metrics and source provenance, then run the complete Android CI suite.
