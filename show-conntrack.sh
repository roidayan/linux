function get_hw_ct {
	echo $(head -1 /proc/net/nf_conntrack_offloaded | awk '{print $2}')
}

function get_nr_queue {
	cat /sys/module/mlx5_core/parameters/nr_workqueue_elm 
}

function get_nr_tot_queue {
        cat /sys/module/mlx5_core/parameters/nr_total_workqueue_elm
}

function get_nr_con_queue {
        cat /sys/module/mlx5_core/parameters/nr_concurrent_workqueue_elm
}

function get_nr_mf_err {
	cat /sys/module/mlx5_core/parameters/nr_mf_err
}

function get_nr_mf_succ {
        cat /sys/module/mlx5_core/parameters/nr_mf_succ
}

function enable_miniflow {
        enable=$1
        sudo sh -c "echo $enable > /sys/module/cls_flower/parameters/enable_miniflow"
}

function conntrack_num {
	sudo conntrack -C
}


ct1=$(get_hw_ct)
nr_wq1=$(get_nr_queue)
nr_twq1=$(get_nr_tot_queue)
nr_mf_me1=$(get_nr_mf_err)
nr_mf_succ1=$(get_nr_mf_succ)

ct_num1=$(conntrack_num)

enable_mf=$(cat /sys/module/cls_flower/parameters/enable_miniflow)

while (true); do
        read -rsn1 -t 1 input
        if [ "$input" = "a" ]; then
                echo "Toggle miniflow merge ($enable_mf)"
                enable_miniflow $enable_mf
		enable_mf=$((1-enable_mf))
        fi

	ct2=$(get_hw_ct)
	nr_wq2=$(get_nr_queue)
	nr_twq2=$(get_nr_tot_queue)
	nr_cwq2=$(get_nr_con_queue)
	nr_mf_me2=$(get_nr_mf_err)
	nr_mf_succ2=$(get_nr_mf_succ)


	ct_num_d=$((ct_num2-ct_num1))
	ct_d=$((ct2-ct1))
	wq_d=$((nr_wq2-nr_wq1))
	twq_d=$((nr_twq2-nr_twq1))
	me_d=$((nr_mf_me2-nr_mf_me1))
	succ_d=$((nr_mf_succ2-nr_mf_succ1))
	ct_num2=$(conntrack_num)

	# swct: nr of software connections
	# ct: nr of offloaded connections (report by /proc/net/nf_conntrack_offload
	# nr_wq: currently nr of queued work
	# nr_twq: total nr of queued work
	# nr_cwq: nr of concurrently running threads
	# ms: nr of miniflows in HW
	# me: nr of failed miniflows
		
	echo "swct: $ct_num2 ($ct_num_d); ct: $ct2 ($ct_d); nr_wq: $nr_wq2 ($wq_d); nr_twq: $nr_twq2 ($twq_d); nr_cwq: $nr_cwq2; ms: $nr_mf_succ2 ($succ_d); ($nr_mf_me2)"


	ct1=$ct2
	nr_wq1=$nr_wq2
	nr_twq1=$nr_twq2
	nr_mf_me1=$nr_mf_me2
	nr_mf_succ1=$nr_mf_succ2

	ct_num1=$ct_num2
done

