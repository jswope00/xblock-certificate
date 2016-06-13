/* Javascript for CertRequestXBlock. */
function CertRequestXBlock(runtime, element) {

    function updatePara(result) {
        $('.string_block', element).text(result.string);
        $('.count_block', element).text(result.count);
        //setTimeout(updateText, 3000);
    }

    var handlerUrl = runtime.handlerUrl(element, 'get_para_text');


   function updateText() {
                $.ajax({
                type: "POST",
                url: handlerUrl,
                data: JSON.stringify({"hello": "world"}),
                success: updatePara
       });
   }


    $(function ($) {
         updateText();
    });
}
