angular.module("services",['restangular'])
.provider('showMsg',function(){
	return {
		$get: function($rootScope) {
			return function(msg){
				$rootScope.$broadcast('msg',{message:msg});
				$("#msgModel").modal("toggle");
				setTimeout(function(){
					$("#msgModel").modal("toggle");
				},1000);
				
			};
		} 
	}
})

.factory('RestFulResponse', function(Restangular) {
	return Restangular.withConfig(function(RestangularConfigurer) {
		RestangularConfigurer.setFullResponse(true);
	});
})
;