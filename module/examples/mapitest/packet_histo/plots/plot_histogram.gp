set size square 1,1
set data style impulses
set grid
set nokey 
set xtics border 0,20
set xlabel 'Character'
set ylabel 'Number of times appeared' 

plot '/tmp/histogram.txt' using 1:2

pause -1
