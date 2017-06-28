$(document).ready(function () {
    $('#calendar').fullCalendar({
        selectable: true,
        defaultView: basicWeek
    });
    $('.btnSaveCahnges').on('click', function () {
        if ($('#from').val() !== '' || $('#to').val() !== '') {
            $('#gridSystemModal').modal('hide');
        }
    });
});
