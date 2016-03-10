angular.module("error",["pascalprecht.translate","ngCookies"])
.config(['$translateProvider', function($translateProvider){

	  $translateProvider.useStaticFilesLoader({
	    prefix: '/data/',
	    suffix: '.json'
	  });

	  $translateProvider.preferredLanguage('en_US');
	  $translateProvider.useCookieStorage();
	}])
.controller("errorCtrl",function($scope,$translate,$interval){
	$scope.number=3;
	$interval(function(){
		if($scope.number!=0){
			$scope.number = $scope.number-1;
		}else{
			window.location.href="/login";
		}
			
		
	},1000);
	$scope.setLang = function(langKey) {
	    $translate.use(langKey);
	  };
						
});
