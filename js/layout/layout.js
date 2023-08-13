$(function () {
    $('#btn-menu').on('click', function(){
        $('#nav-profile-dropdown').toggleClass('hidden')
    })

    setTimeout(() => {
        $('#notification-container').remove()
    }, 4000);
});