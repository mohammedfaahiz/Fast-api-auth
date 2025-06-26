.PHONY: run black pylint

# Run the FastAPI app
run:
	.venv\Scripts\uvicorn api:app --reload

# black the code using Black
black:
	.venv\Scripts\black .

# Run pylint
pylint:
	.venv\Scripts\python -m pylint main.py
