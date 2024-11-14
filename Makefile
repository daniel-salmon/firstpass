openapi-schema:
	python -c "import json; from app.main import app; print(json.dumps(app.openapi()))" > firstpass-openapi.json

client:
	sudo rm -rf client/
	docker run \
		--rm \
		-v "${PWD}:/local" \
		openapitools/openapi-generator-cli generate \
		-i local/firstpass-openapi.json \
		-g python \
		-o /local/client/python
