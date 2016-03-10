(function () {
    var module;

    module = angular.module('angularBootstrapSearchdrowup', []);

    module.directive('searchDrowup',function () {
        return {
            restrict: 'E',   // default value
            templateUrl:'../resources/angular/searchDropdownComponent/search_dropdown_template.html',
            replace: true,
            scope: {
                initData: '=',
                initSelect:'=',
                onSearch:'&'
            },
            link: function (scope, element, attrs) {

                if (attrs.drowupText == null) {
                	if(scope.initData[0].fieldName == null){
                		scope.initSelect.drowupText = scope.initData[0]
                	} else {
                		scope.initSelect.drowupText = scope.initData[0].fieldName
                	}
                }

                scope.set_drowuptext = function (name) {
                    scope.initSelect.drowupText = name;
                    scope.initSelect.searchText = "";
                    angular.forEach(scope.initData, function(data){
                    	if(data.fieldName == null){
                    		return;
                    	}
                    	if(data.fieldName == name){
                            scope.isSelector = data.fieldType == 1 ? true : false ;
                            console.log(data.fieldName);
                            scope.selectorM = data.fieldValue;
                			return;
                    	}
                    });
                   scope.onSearch();
                };
                
                scope._search = function () {
                    //console.log(scope.initSelect.drowupText+"/"+scope.initSelect.searchText);
                    scope.onSearch();
                };


                // 重置
                scope._reset = function () {
                    scope.initSelect.searchText = "";
                    scope.onSearch();
                }
            }}
    }
    );



}).call(this);
