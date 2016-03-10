angular.module("wirelessManager.hapManagerModule",[])
.controller("hapManagerCtrl",function(showMsg,$scope,$http,$location,$state,Restangular,$resource,RestFulResponse,destroyInfoMsg,destroyErrorMsg,$translate){
    /**
	 * 显示信息配置
	 */
    $scope.message = {
            mytype: 'info',
            show:false,
            content: ''
    };
	
	/**
	 * 页面域对象初始化
	 */
	$state.go("wirelessManager/hapManager/index.query");
	$scope.hapManager = {};
	$scope.hapManager.haps ={};
	$scope.hapManager.mySearchForm = {};
	
	 /**
	 * 查詢操作
	 */
	function findAll(){	
		Restangular.one('haps').get().then(function(data){
			if(data.success){
				$scope.hapManager.haps = data.result;
			}
				
		});
	};
	//初始化查询
	findAll();
		
	/**
	 * 条件查询
	 */
	$scope.search = function(){
		findAll();
	}
	
	/**
	 * 跳转到创建页面
	 */
	$scope.toCreate = function(item){
		$scope.hapManager.currentPlatformParam = item;
		$state.go("^.create");
	}

	/**
	 * 执行保存操作
	 */
	$scope.save = function(){
		
		Restangular.one('haps').customPOST($scope.hapManager.newHap).then(function(data){
			$scope.hapManager.newHap = {};
			findAll();
			$state.go("^.query");
			if(data.success === true){
				destroyInfoMsg($scope,data.result,true,3000);
			}else{//保存失败
				destroyErrorMsg($scope,data.result,true,3000);
			}
			
		});
	}
	
	/**
	 * 跳转到编辑页面
	 */
	$scope.toEdit = function(item){
		$scope.isFilterDisable=true;
		$scope.hapManager.currentHap = item;
		$state.go("^.edit");
	}
	
	/**
	 * 执行更新操作
	 */
	$scope.update = function(){
		var tHap = $scope.hapManager.currentHap;
		Restangular.all('hap/'+tHap.mac).customPUT(tHap).then(function(data){
			$scope.hapManager.currentHap = {};
			findAll();
			$state.go("^.query");
			if(data.success === true){
				destroyInfoMsg($scope,data.result,true,3000);
			}else{//修改失败
				destroyErrorMsg($scope,data.result,true,3000);
			}
			
		});
	}
	
	/**
	 * 执行删除操作
	 */
	$scope.delete = function(item){
		bootbox.confirm($translate.instant('delete_before'), function(result) {
		if(result){
			Restangular.all('hap/'+item.mac).remove().then(function(data){
				if(data.success === true){
					findAll();
					destroyInfoMsg($scope,data.result,true,3000);
				}else{
					destroyInfoMsg($scope,'delete_msg_info_error',true,3000);
				}
			});	
		}
		});
	};
	
	
	/**
	 * 返回按钮
	 */
	$scope.backToList = function(){
		$state.go("^.query");
	}
})
;