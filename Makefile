run-server:
	docker compose up --build server

run-client:
	docker compose run --rm --build client /bin/bash