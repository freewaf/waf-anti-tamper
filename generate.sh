
DESFILENAME=./include/public.h
SRCFILENAME=./include/public.h.in

rm -rf  $DESFILENAME

cat - $SRCFILENAME <<EOF > $DESFILENAME
EOF

sed -i "/endif/i\\$(echo $1)" $DESFILENAME
