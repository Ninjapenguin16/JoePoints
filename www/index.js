function truncate(text, max = 20) {
    const str = String(text || '');
    return str.length > max ? str.substring(0, max) + '...' : str;
}

async function fetchLeaderboard() {
    try {
        const resp = await fetch('/api/getall', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({})
        });
        const users = await resp.json();

        // Sort by points descending
        users.sort((a, b) => b.points - a.points);

        const tbody = document.querySelector('#leaderboard tbody');
        tbody.innerHTML = '';
        users.forEach((u, i) => {
            const row = document.createElement('tr');
            
            const posCell = document.createElement('td');
            posCell.textContent = String(i + 1);
            row.appendChild(posCell);
            
            const nameCell = document.createElement('td');
            nameCell.textContent = `${truncate(u.first)} ${truncate(u.last)}`;
            row.appendChild(nameCell);
            
            const pointsCell = document.createElement('td');
            pointsCell.textContent = String(u.points);
            row.appendChild(pointsCell);
            
            tbody.appendChild(row);
        });
    } catch (err) {
        console.error('Error fetching leaderboard:', err);
        const tbody = document.querySelector('#leaderboard tbody');
        tbody.innerHTML = '<tr><td colspan="3">Failed to load leaderboard</td></tr>';
    }
}

// Initial fetch
fetchLeaderboard();
// Refresh leaderboard every 5 seconds
setInterval(fetchLeaderboard, 5000);
