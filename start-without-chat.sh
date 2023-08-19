#!/bin/bash
cd "$(dirname $0)" || exit
export CHAT=deny
exec ./app.mjs