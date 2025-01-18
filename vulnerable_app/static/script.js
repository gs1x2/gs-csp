document.addEventListener('DOMContentLoaded', () => {
    document.body.classList.add('loaded');

    // Отображение кнопок при ховере реализовано через CSS :hover,

    const noteItems = document.querySelectorAll('.note-item');
    noteItems.forEach(item => {
        const contentElem = item.querySelector('.note-content');
        const editForm = item.querySelector('.edit-form');
        const editBtn = item.querySelector('.edit-btn');
        const actions = item.querySelector('.actions');

        // Показать действия при наведении
        item.addEventListener('mouseenter', () => {
            actions.style.display = 'inline-block';
        });
        item.addEventListener('mouseleave', () => {
            // Проверяем, не в режиме редактирования мы
            if (editForm.style.display === 'none') {
                actions.style.display = 'none';
            }
        });

        // Режим редактирования
        editBtn.addEventListener('click', () => {
            contentElem.style.display = 'none';
            editForm.style.display = 'inline-block';
        });
    });
});
