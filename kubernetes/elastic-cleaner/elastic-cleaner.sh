# Loop
URL="http://localhost:9200"
from=15
to=30
for i in `seq $from $max`
do
    # Delete index if older than i days
    DATE=`date -d "$dataset_date - $i days" +%Y.%m.%d`
    echo "Deleting day: $DATE"
	curl -XDELETE "$URL/logstash-$DATE"
done