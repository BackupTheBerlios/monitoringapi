set size square 1,1
set data style impulses
set grid
set nokey 
set xtics border 0,10000
set xlabel 'Ports'
set ylabel 'Number of Packets' 

plot '/tmp/distribution.txt' using 1:2

pause -1
