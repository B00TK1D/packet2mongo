#!/bin/bash

docker rm -f packt2mongo_db
docker run -p 27017:27017 -d --name packt2mongo_db mongo