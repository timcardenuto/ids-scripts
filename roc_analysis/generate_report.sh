#!/bin/bash

source /opt/rh/rh-ruby22/enable
dt=$(date '+%Y%m%d-%H%M%S')

asciidoctor-pdf $1 -o docs/roc-report-$dt.pdf

asciidoctor $1 -o docs/roc-report-$dt.html
