angular.module("login",["pascalprecht.translate","ngCookies"])
.config(['$translateProvider', function($translateProvider){

	  $translateProvider.useStaticFilesLoader({
	    prefix: '/data/',
	    suffix: '.json'
	  });

	  $translateProvider.preferredLanguage('en_US');
	  $translateProvider.useCookieStorage();
	}])
.controller("loginAlarmCtrl",function($scope){
	$scope.loginAlarmTitle = "Note";
	$scope.loginAlarmMsg="Are you sure to login";
})
.controller("loginCtrl",function($scope,$translate){
	
	var addr = location.href;
	if(addr.indexOf("error1")!=-1){
		//Username or password is error
		$scope.message = 'loginError1';
		$("#msgDiv").show(500);
		setTimeout(function () { 
			 $("#msgDiv").slideUp(); 
			    }, 3000);
	}else if(addr.indexOf("error2")!=-1){
		$scope.message = 'Login first please';
		$("#msgDiv").show(500);
		 setTimeout(function () { 
		 $("#msgDiv").slideUp(); 
		    }, 3000);
	}else if(addr.indexOf("error3")!=-1){
		//User is locked
		$scope.message = 'loginError3';
		$("#msgDiv").show(500);
		 setTimeout(function () { 
		 $("#msgDiv").slideUp(); 
		    }, 3000);
	}else if(addr.indexOf("error5")!=-1){
		//5 consecutive error, the account will lock
		$scope.message = 'loginError5';
		$("#msgDiv").show(500);
		 setTimeout(function () { 
		 $("#msgDiv").slideUp(); 
		    }, 3000);
	}else if(addr.indexOf("error4")!=-1){
		//login error
		$scope.message = 'login fault';
		$("#msgDiv").show(500);
		 setTimeout(function () { 
		 $("#msgDiv").slideUp(); 
		    }, 3000);
	}
	$scope.setLang = function(langKey) {
	    $translate.use(langKey);
	  };
	
	$scope.mySubmitDemo = function(){
		$('#loginAlarmTemp').modal({keyboard: true});
	}
	
	$scope.loginStart = function(){
		//document.getElementById("password").value = hex_md5(document.getElementById("password").value).toUpperCase();
        //document.f.submit();
		window.location.href="home.html";
	}
});
