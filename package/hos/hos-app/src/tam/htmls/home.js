angular.module("home",["ngAnimate",
                       "ngSanitize",
                       "ui.router",
                       "restangular",
                       "ngResource",
                       "pascalprecht.translate",
                       "ngCookies",
                       "services",
                       "ui.bootstrap",
                       "angularBootstrapCheckbox",
                       "angularBootstrapSearchdrowup",
                       "angularBootstrapDrowup",
                       "mgcrea.ngStrap",
                       "mgcrea.ngStrap.helpers.dateParser",
                       "flow",
                       "tipService",
                       "homeMain",
					   "wirelessManagerModule",
					   "wirelessManager.hapManagerModule"
                       ])
.constant("categoryActiveClass","active")
    .config(function($datepickerProvider) {
        angular.extend($datepickerProvider.defaults, {
            dateFormat: 'dd/MM/yyyy',
            startWeek: 1
        });

    })
.config(function(RestangularProvider,$httpProvider) {
    RestangularProvider.addResponseInterceptor(function(data, operation, what, url, response, deferred) {
      var extractedData;
//      if(!(angular.isObject(data)||angular.isArray(data))){
//    	  //window.location.href="/login.html";
//      }
      if(response.status!==200){
    	  window.location.href="/login.html";
      }
      var loginReg=/<!DOCTYPE html>/;
      if(loginReg.test(data)){
    	  window.location.href="/login.html";
      }
      
      if (operation === "getList") {
        extractedData = data.content;
        extractedData.totalPages = data.totalPages;
        extractedData.totalElements = data.totalElements;
        extractedData.size = data.size;
      } else {
    	
    		
    		extractedData = data;
      }
      
      return extractedData;
    });
    RestangularProvider.setBaseUrl("/");
    $httpProvider.interceptors.push(function(){
    	return {
    		response:function(response){
    			if(response.status==302){
    				window.location.href="/login.html";
    			}
    			return response;
    		}
    	}
    });
    
    
})

.run(function(Restangular,showMsg){

	Restangular.setErrorInterceptor(function(response, deferred, responseHandler) {
    	
    	if(response.status===500){
    		showMsg('500 error');
    	}else if(response.status===405){
    		showMsg('405 error');
    	}else if(response.status==302){
			window.location.href="/login.html";
		}
    });
	
})
.config(function($stateProvider, $urlRouterProvider,$translateProvider) {
				$translateProvider.useStaticFilesLoader({
				    prefix: '/data/',
				    suffix: '.json'
				  });
				  $translateProvider.preferredLanguage('en_US');
				  $translateProvider.useCookieStorage();
				  
				  $stateProvider
					.state('home', {
					  url: "/home",
					  templateUrl: "home/index.html",
					  controller: 'homeMainCtrl'
					})
					// demo
					.state('wirelessManager/hapManager/index', {
						url: "/wirelessManager/hapManager/index",
						templateUrl: "wirelessManager/hapManager/index.html",
						controller: 'hapManagerCtrl'
					})			

				})
.controller("homeCtrl",function($scope,$window,$http,$state,categoryActiveClass,Restangular,$translate){

   // 提示信息的设置

	/* l18n*/
	var language =  $translate.use() ||
    $translate.storage().get($translate.storageKey()) ||
    $translate.preferredLanguage();
	if(language==='en_US'){
		$scope.i18n = "中文";
	}else{
		$scope.i18n = "English";
	}
	
	/*data start*/
	$scope.homeManager = {};
	$scope.hapManager={};
	/*data end*/
	
	/**
	*演示,hap列表展示
	**/
	$state.go("wirelessManager/hapManager/index.query");
	
	/**
	*登出
	**/
	$scope.selectCategory = function (newCategory) {

		if(newCategory=="logout"){
			$('#logout').modal('toggle');
		}					
	}
							
	$scope.setLang = function() {
		if($scope.i18n==='English'){
			$scope.i18n = '中文';
			$translate.use('en_US');
		}else{
			$scope.i18n = 'English';
			$translate.use('zh_CH');
		}
		
	    setTimeout(function(){
	    	$state.reload();
	    },200);
	  };
	  
	 $scope.logout = function(){
		window.location.href="login.html";
	}
	 
})
.controller('logout',function($scope){
	$scope.logoutTitle = "note";
	$scope.logoutMsg="do you sure to logut";
})
.controller('modelMsg',function($scope){
	$scope.msgTitle = "note";
	$scope.$on('msg',function(event,args){
		$scope.message = args.message;
		
	})
	
})
;

