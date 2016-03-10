angular.module("homeMain",[])
.controller("homeMainCtrl",function($scope,Restangular,destroyInfoMsg){
	/**
	 * 显示信息配置
	 */
    $scope.message = {
            mytype: 'info',
            show:false,
            content: ''
        };
		
})
