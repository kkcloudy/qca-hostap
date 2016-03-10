angular.module("wirelessManagerModule",[])
//hap demo
.config(function($stateProvider){
	$stateProvider
	.state('wirelessManager/hapManager/index.query', {
		views:{
			"list":{
				templateUrl: "wirelessManager/hapManager/view.html"
			},
			"filter":{
				templateUrl: "wirelessManager/hapManager/filter.html",
			}
		}
	})
	.state('wirelessManager/hapManager/index.create', {
		views:{
			"list":{
				templateUrl: "wirelessManager/hapManager/create.html"
			}
		}
	})		
	.state('wirelessManager/hapManager/index.edit', {
		views:{
			"list":{
				templateUrl: "wirelessManager/hapManager/edit.html"
			}
		}
	})	
})
; 