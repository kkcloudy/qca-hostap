function selectedCategoryListFn(ele){
				$("#accordion a").each(function(){
					if($(this).hasClass('red'))
						$(this).removeClass('red');
				});
				
				$(ele).addClass('red');
			}