#!/bin/bash
docker run --rm --env-file .env -v "$(pwd)":/usr/share/GeoIP maxmindinc/geoipupdate:latest
