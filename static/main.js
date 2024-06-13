$(function() {
    $('#nav').click(function(){
        $(this).toggleClass('open')
        $("header ul").fadeToggle()
    })
})

