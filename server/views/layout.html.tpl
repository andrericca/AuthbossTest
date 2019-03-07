<!DOCTYPE html>
<html>
<head>
</head>
<body class="container-fluid" style="padding-top: 15px;">
	<nav class="navbar navbar-default">
		<div class="container-fluid">
			</div>
			<div class="collapse navbar-collapse" id="bs-example-navbar-collapse-1">
				<ul class="nav navbar-nav navbar-right">
					{{if not .loggedin}}
					<li><a href="auth/register">Register</a></li>
					<li><a href="/auth/recover">Recover</a></li>
					<li><a href="/login"><i class="fa fa-sign-in"></i> Login</a></li>
					{{else}}
					<li class="dropdown">
						<a href="#" class="dropdown-toggle" data-toggle="dropdown" role="button" aria-expanded="false">Welcome {{.current_user_name}}! <span class="caret"></span></a>
						<ul class="dropdown-menu" role="menu">
							<li>
								<a href="/auth/logout">
									<i class="fa fa-sign-out"></i> Logout
								</a>
							</li>
						</ul>
					</li>
				</ul>
			</div>
		</div>
	</nav>
</body>
</html>
