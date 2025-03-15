#!/bin/bash

JOERNDIR="/home/umd-user/Desktop/navex_project/joern-repo"
SCRIPTDIR="/home/umd-user/Desktop/navex_project/navex_tests"
WORKSPACEDIR="/home/umd-user/Desktop/navex_project/navex_utils"
declare -a apps=("oscommerce-2.3.4.1" "mybloggie214" "hotcrp-2.60" "hotcrp-2.100" "WebChess_0.9.0" "SchoolMate_v1.5.4" "WeBid" "wordpress" "zen-cart-v1.5.5" "geccBBlite-0.1" "faqforge-1.3.2")

cd $SCRIPTDIR
for app in "${apps[@]}"; do
cd $WORKSPACEDIR/code
joern-parse $SCRIPTDIR/$app
$JOERNDIR/joern --script $WORKSPACEDIR/src/RunNavex.scala --params path=$WORKSPACEDIR/src/cpg.bin,name=$app --import SanitizationFilter.scala,Constants.scala,NavexMain.scala
done