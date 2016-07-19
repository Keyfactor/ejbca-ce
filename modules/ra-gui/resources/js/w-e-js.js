/** scroll-to-top functionality for mobile and tablets */
function showHideScrollToTop() {
    if ($(window).width() < 1024 && $(this).scrollTop() > 300) {
        $('#web-express-scroll-to-top').fadeIn();  // show button
    } else {
        $('#web-express-scroll-to-top').fadeOut(); // hide button
    }
}

$(document).ready(function() {
    showHideScrollToTop();
    
    // check to see if the window width is smaller than 1024px + if window is in the bottom. if so, show element. if not, hide it
    $(window).scroll(function() {
        showHideScrollToTop();
    });

    // click event to scroll to top
    $('#web-express-scroll-to-top').click(function() {
        $('html, body').animate(
            {scrollTop : 0}, 
            400
        );
        
        return false;
    });
});
